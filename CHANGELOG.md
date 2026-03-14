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

### Changed

- Database migration steps v4→v5 and v5→v6 now use inline schemas to avoid forward-compatibility issues with later table definitions

### Fixed

- Vault restore no longer prints raw Python log lines in the TUI (demoted to debug level; progress is shown via LogPanel callback)
