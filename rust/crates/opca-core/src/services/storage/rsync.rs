//! Rsync-based storage backend.
//!
//! Uploads content to remote servers via `rsync -avz` over SSH.
//! URI format: `rsync://user@host/path/to/destination`

use std::io::Write;
use std::process::Command;

use crate::error::OpcaError;

use super::StorageBackend;

/// Rsync-based storage backend.
pub struct StorageRsync;

impl StorageRsync {
    /// Parse an rsync URI into the destination string.
    ///
    /// `rsync://user@host/path/to/dest` -> `user@host/path/to/dest`
    fn parse_destination(uri: &str) -> Result<String, OpcaError> {
        let rest = uri
            .strip_prefix("rsync://")
            .ok_or_else(|| OpcaError::Storage(format!("Invalid rsync URI: {uri}")))?;

        if rest.is_empty() {
            return Err(OpcaError::Storage("Empty rsync destination".to_string()));
        }

        Ok(rest.to_string())
    }

    /// Extract `user@host` (or just `host`) from an rsync URI for SSH
    /// connectivity testing.
    fn parse_host(uri: &str) -> Result<String, OpcaError> {
        let rest = uri
            .strip_prefix("rsync://")
            .ok_or_else(|| OpcaError::Storage(format!("Invalid rsync URI: {uri}")))?;

        // Take everything before the first '/' after the authority
        let host = rest.split('/').next().unwrap_or(rest);
        if host.is_empty() {
            return Err(OpcaError::Storage("Empty rsync host".to_string()));
        }

        Ok(host.to_string())
    }
}

impl StorageBackend for StorageRsync {
    fn upload(&self, content: &[u8], uri: &str) -> Result<(), OpcaError> {
        let destination = Self::parse_destination(uri)?;

        // Write content to a temp file
        let mut tmp = tempfile::NamedTempFile::new()
            .map_err(|e| OpcaError::Io(format!("Failed to create temp file: {e}")))?;
        tmp.write_all(content)
            .map_err(|e| OpcaError::Io(format!("Failed to write temp file: {e}")))?;
        tmp.flush()
            .map_err(|e| OpcaError::Io(format!("Failed to flush temp file: {e}")))?;

        let tmp_path = tmp.path().to_string_lossy().to_string();

        let output = Command::new("rsync")
            .args(["-avz", &tmp_path, &destination])
            .output()
            .map_err(|e| OpcaError::Storage(format!("Failed to run rsync: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OpcaError::Storage(format!("rsync failed: {stderr}")));
        }

        Ok(())
    }

    fn test_connection(&self, uri: &str) -> Result<(), OpcaError> {
        let host = Self::parse_host(uri)?;

        let output = Command::new("ssh")
            .args([
                "-o", "ConnectTimeout=5",
                "-o", "BatchMode=yes",
                &host,
                "true",
            ])
            .output()
            .map_err(|e| OpcaError::Storage(format!("Failed to run ssh: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(OpcaError::Storage(format!(
                "SSH connection to {host} failed: {stderr}"
            )));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_destination() {
        let dest =
            StorageRsync::parse_destination("rsync://user@host.example.com/var/www/pki/").unwrap();
        assert_eq!(dest, "user@host.example.com/var/www/pki/");
    }

    #[test]
    fn test_parse_destination_invalid_scheme() {
        let result = StorageRsync::parse_destination("s3://bucket/key");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_destination_empty() {
        let result = StorageRsync::parse_destination("rsync://");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_host() {
        let host =
            StorageRsync::parse_host("rsync://deploy@web.example.com/var/www/pki/").unwrap();
        assert_eq!(host, "deploy@web.example.com");
    }

    #[test]
    fn test_parse_host_no_user() {
        let host = StorageRsync::parse_host("rsync://web.example.com/var/www/").unwrap();
        assert_eq!(host, "web.example.com");
    }

    #[test]
    fn test_parse_host_empty() {
        let result = StorageRsync::parse_host("rsync://");
        assert!(result.is_err());
    }
}
