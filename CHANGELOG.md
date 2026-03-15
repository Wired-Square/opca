# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Empty vault gating: sidebar items and keyboard shortcuts for screens that require a CA are disabled until a CA is initialised or restored
- Empty vault badge in the screen header when connected to a vault with no CA
- Vault Backup tab is disabled on an empty vault; the screen defaults to Restore
- Certificate import: passphrase field for encrypted private keys with automatic decryption and re-export as unencrypted PKCS8 PEM
- Certificate import: certificate chain field for intermediate CA certificates, stored as `certificate_chain` in 1Password
- `certificate_chain` field on CertificateBundle for holding intermediate CA PEM data
- `chain_item` key in DEFAULT_OP_CONF for the 1Password field label

### Changed

- Certificate import screen now calls CA services directly instead of shelling out via capture_handler(), improving error handling and chain support
- Certificate import stores chain data via store_certbundle() when provided

### Fixed

- TUI no longer shows raw Python log lines (e.g. vault_lock INFO messages) in the terminal; StreamHandlers are removed on startup and restored on exit

## [Unreleased - Infrastructure]

### Added

- Database schema v7: certificate metadata columns (cert_type, not_before, key_type, key_size, issuer, SAN) on certificate_authority and external_certificate tables
- Database schema v7: csr_pem column on csr table
- Database schema v7: crl_metadata, openvpn_template, and openvpn_profile tables with CRUD helpers
- CommandQueue service for batching and debouncing 1Password write operations
- Certificate metadata extraction (key type, key size, SAN) in CA format_db_item()
- VaultLock: advisory locking via a 1Password Secure Note (CA_Lock) to serialise mutating operations across CLI and TUI
- Stale-database detection on store_ca_database() using download fingerprint comparison
- TuiContext.locked_mutation() context manager for TUI screens that acquires the vault lock and refreshes the CA database

### Changed

- Database migration steps v4→v5 and v5→v6 now use inline schemas to avoid forward-compatibility issues with later table definitions
- CLI commands (ca init/import, cert create/renew/revoke/import, crl create) now acquire the vault lock before mutating operations
- TUI screens (cert create/renew/revoke, CRL generate, CA config save/init) now use locked_mutation()

### Fixed

- Vault restore no longer prints raw Python log lines in the TUI (demoted to debug level; progress is shown via LogPanel callback)
- count_certs() no longer crashes when fetchone() returns None on a replaced database connection
- TUI e2e test helper connect_and_get_dashboard now waits for the Dashboard's _show_welcome worker to complete
