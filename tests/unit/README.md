# Unit Tests

This directory contains comprehensive unit tests for OPCA's core functionality.

## Test Coverage

### `test_datetime.py` - DateTime Utilities (39 tests)
Tests for `opca.utils.datetime` module:
- **Format/Parse operations**: OpenSSL, text, and compact formats
- **Format/Parse roundtrips**: Ensures bidirectional consistency
- **Timezone handling**: Naive datetimes, UTC, and timezone conversions
- **Current time functions**: `now_utc()`, `now_utc_plus()`, `now_utc_str()`
- **Edge cases**: Leap years, Y2K, extreme timezones, far future dates

### `test_files.py` - File Utilities (31 tests)
Tests for `opca.utils.files` module:
- **Read operations**: Binary/text files, permissions, error handling
- **Write operations**: Atomic writes, permissions (0o600), directory creation
- **Bulk file parsing**: CN entries, SANs, comments, whitespace handling
- **Roundtrip operations**: Read/write consistency
- **Edge cases**: Large files, Unicode, binary data

### `test_database.py` - Certificate Authority Database (37 tests)
Tests for `opca.services.database.CertificateAuthorityDB` class:
- **Initialization**: Schema creation, indexes, config setup
- **Config operations**: Get/update config attributes, None handling
- **Serial management**: Certificate and CRL serial incrementing
- **Certificate CRUD**: Add, query (by serial/CN/title), update, count
- **Database processing**: Certificate categorization (valid/expired/revoked/expiring soon)
- **Export/Import**: SQL and binary SQLite formats
- **Schema migration**: Version upgrade paths
- **Edge cases**: Missing values, concurrent operations

## Running Tests

Run all unit tests:
```bash
pytest tests/unit/ -v
```

Run specific test file:
```bash
pytest tests/unit/test_datetime.py -v
```

Run specific test class:
```bash
pytest tests/unit/test_database.py::TestDatabaseInitialization -v
```

Run with coverage:
```bash
pytest tests/unit/ --cov=opca --cov-report=html
```

## Test Organization

Tests are organized by the module they test:
- `test_datetime.py` → `opca.utils.datetime`
- `test_files.py` → `opca.utils.files`
- `test_database.py` → `opca.services.database`

Each test file uses class-based organization to group related tests:
- One class per major function or feature area
- Descriptive test names following `test_<what_it_does>` pattern
- Comprehensive docstrings explaining test purpose

## Future Test Additions

Planned test coverage:
- `test_cert.py` - CertificateBundle class (key generation, CSR, validation)
- `test_ca.py` - CertificateAuthority class (signing, revocation, CRL)
- `test_storage.py` - Storage backends (S3, Rsync)
- `test_formatting.py` - Terminal output formatting
- `test_crypto.py` - Cryptographic utilities

## Notes

- Tests use pytest fixtures (`tmp_path`) for file system isolation
- All tests are independent and can run in any order
- No external dependencies (1Password, AWS) required for unit tests
- Tests verify both success and error paths
