# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
